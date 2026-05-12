use kacs_core::{
    pre_sacl_walk, ClaimValue, GenericMapping, IntegrityLevel, KacsError, PipContext,
    PrivilegeProvenance, SecurityDescriptor, ACCESS_SYSTEM_SECURITY, READ_CONTROL, SE_SACL_PRESENT,
    SE_SELF_RELATIVE, WRITE_DAC, WRITE_OWNER,
};

const SYSTEM_MANDATORY_LABEL_ACE_TYPE: u8 = 0x11;
const SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE: u8 = 0x12;
const SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: u8 = 0x13;
const SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE: u8 = 0x14;
const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: u32 = 0x0000_0002;
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

fn utf16_cstr(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for unit in value.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes
}

fn int64_claim(name: &str, value: i64) -> Vec<u8> {
    let mut bytes = Vec::new();
    let values_start = 20usize;
    let name_offset = 28usize;

    bytes.extend_from_slice(&(name_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&0x0001u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&(values_start as u32).to_le_bytes());
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes.extend_from_slice(&utf16_cstr(name));
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

fn resource_attribute_ace(flags: u8, application_data: &[u8]) -> Vec<u8> {
    let sid = sid_bytes([0, 0, 0, 0, 0, 1], &[0]);
    let unpadded_size = 8 + sid.len() + application_data.len();
    let size = (unpadded_size + 3) & !3;
    let mut bytes = Vec::with_capacity(size);
    bytes.push(SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE);
    bytes.push(flags);
    bytes.extend_from_slice(&(size as u16).to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&sid);
    bytes.extend_from_slice(application_data);
    bytes.resize(size, 0);
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
fn no_sacl_leaves_pre_sacl_state_unchanged() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let sd_bytes = sd_with_sacl(&owner, None);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");
    let initial_provenance = PrivilegeProvenance {
        security_granted: ACCESS_SYSTEM_SECURITY,
        ..PrivilegeProvenance::default()
    };

    let result = pre_sacl_walk(
        &sd,
        IntegrityLevel::Medium,
        TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
        0,
        PipContext::default(),
        &mapping(),
        ACCESS_SYSTEM_SECURITY,
        READ_CONTROL | ACCESS_SYSTEM_SECURITY,
        ACCESS_SYSTEM_SECURITY,
        initial_provenance,
    )
    .expect("pre-sacl walk should succeed");

    assert_eq!(result.decided, ACCESS_SYSTEM_SECURITY);
    assert_eq!(result.granted, READ_CONTROL | ACCESS_SYSTEM_SECURITY);
    assert_eq!(result.privilege_granted, ACCESS_SYSTEM_SECURITY);
    assert_eq!(result.mandatory_decided, 0);
    assert_eq!(result.resource_attributes, vec![]);
    assert_eq!(result.policy_sids, vec![]);
    assert_eq!(result.provenance, initial_provenance);
}

#[test]
fn composed_pre_sacl_applies_mic_then_pip_and_returns_metadata() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let high = sid_bytes([0, 0, 0, 0, 0, 16], &[12288]);
    let trust = sid_bytes([0, 0, 0, 0, 0, 19], &[512, 4096]);
    let policy = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 99]);
    let sacl = acl_bytes(&[
        resource_attribute_ace(0, &int64_claim("Level", 3)),
        basic_ace(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, 0, 0, &policy),
        basic_ace(
            SYSTEM_MANDATORY_LABEL_ACE_TYPE,
            0,
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            &high,
        ),
        basic_ace(SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, 0, READ_CONTROL, &trust),
    ]);
    let sd_bytes = sd_with_sacl(&owner, Some(&sacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let result = pre_sacl_walk(
        &sd,
        IntegrityLevel::Medium,
        TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
        0,
        PipContext {
            pip_type: 512,
            pip_trust: 1024,
        },
        &mapping(),
        ACCESS_SYSTEM_SECURITY,
        READ_CONTROL | WRITE_DAC | ACCESS_SYSTEM_SECURITY,
        ACCESS_SYSTEM_SECURITY,
        PrivilegeProvenance::default(),
    )
    .expect("pre-sacl walk should succeed");

    assert_eq!(
        result.decided,
        ACCESS_SYSTEM_SECURITY | WRITE_DAC | WRITE_OWNER | 0x0000_0020
    );
    assert_eq!(result.granted, READ_CONTROL);
    assert_eq!(result.privilege_granted, 0);
    assert_eq!(
        result.mandatory_decided,
        WRITE_DAC | WRITE_OWNER | 0x0000_0020 | ACCESS_SYSTEM_SECURITY
    );
    assert_eq!(result.resource_attributes.len(), 1);
    assert_eq!(result.resource_attributes[0].name, "Level");
    assert_eq!(
        result.resource_attributes[0].values,
        vec![ClaimValue::Int64(3)]
    );
    assert_eq!(result.policy_sids.len(), 1);
    assert_eq!(result.policy_sids[0].as_bytes(), policy.as_slice());
}

#[test]
fn first_labels_only_still_apply_inside_composed_pre_sacl_walk() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let first_label = sid_bytes([0, 0, 0, 0, 0, 16], &[4096]);
    let second_label = sid_bytes([0, 0, 0, 0, 0, 16], &[12288]);
    let first_trust = sid_bytes([0, 0, 0, 0, 0, 19], &[512, 4096]);
    let second_trust = sid_bytes([0, 0, 0, 0, 0, 19], &[1024, 8192]);
    let policy = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 42]);
    let sacl = acl_bytes(&[
        basic_ace(
            SYSTEM_MANDATORY_LABEL_ACE_TYPE,
            0,
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            &first_label,
        ),
        basic_ace(
            SYSTEM_MANDATORY_LABEL_ACE_TYPE,
            0,
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            &second_label,
        ),
        basic_ace(
            SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
            0,
            READ_CONTROL,
            &first_trust,
        ),
        basic_ace(
            SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
            0,
            WRITE_DAC,
            &second_trust,
        ),
        basic_ace(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, 0, 0, &policy),
    ]);
    let sd_bytes = sd_with_sacl(&owner, Some(&sacl));
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let result = pre_sacl_walk(
        &sd,
        IntegrityLevel::Medium,
        TOKEN_MANDATORY_POLICY_NO_WRITE_UP,
        0,
        PipContext {
            pip_type: 512,
            pip_trust: 1024,
        },
        &mapping(),
        0,
        READ_CONTROL | WRITE_DAC,
        0,
        PrivilegeProvenance::default(),
    )
    .expect("pre-sacl walk should succeed");

    assert_eq!(result.granted, READ_CONTROL);
    assert_eq!(
        result.mandatory_decided,
        WRITE_DAC | WRITE_OWNER | 0x0000_0020 | ACCESS_SYSTEM_SECURITY
    );
    assert_eq!(result.policy_sids.len(), 1);
}

#[test]
fn malformed_resource_attribute_payload_fails_closed_through_pre_sacl_walk() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let high = sid_bytes([0, 0, 0, 0, 0, 16], &[12288]);
    let sacl = acl_bytes(&[
        resource_attribute_ace(0, &[1, 2, 3, 4]),
        basic_ace(
            SYSTEM_MANDATORY_LABEL_ACE_TYPE,
            0,
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            &high,
        ),
    ]);
    let sd_bytes = sd_with_sacl(&owner, Some(&sacl));
    let err = SecurityDescriptor::parse(&sd_bytes).expect_err("malformed metadata must fail");
    assert_eq!(err, KacsError::InvalidClaimFormat("claim entry header"));
}
