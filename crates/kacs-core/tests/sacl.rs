mod common;
use common::{acl_bytes, basic_ace, resource_attribute_ace, sid_bytes};
use kacs_core::{
    extract_sacl_metadata, ClaimValue, KacsError, SecurityDescriptor, CLAIM_TYPE_BOOLEAN,
    CLAIM_TYPE_OCTET, CLAIM_TYPE_SID, CLAIM_TYPE_STRING, CLAIM_TYPE_UINT64, SE_SACL_PRESENT,
    SE_SELF_RELATIVE,
};

const SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: u8 = 0x13;
const INHERIT_ONLY_ACE: u8 = 0x08;


fn utf16_cstr(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for unit in value.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes
}

fn int64_values_claim(name: &str, values: &[i64]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let value_count = values.len();
    let offsets_start = 16usize;
    let values_start = offsets_start + (value_count * 4);
    let name_offset = values_start + (value_count * 8);

    bytes.extend_from_slice(&(name_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&0x0001u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&(value_count as u32).to_le_bytes());
    for index in 0..value_count {
        bytes.extend_from_slice(&((values_start + (index * 8)) as u32).to_le_bytes());
    }
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&utf16_cstr(name));
    bytes
}

fn int64_claim(name: &str, value: i64) -> Vec<u8> {
    int64_values_claim(name, &[value])
}

fn u64_values_claim(name: &str, value_type: u16, values: &[u64]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let value_count = values.len();
    let offsets_start = 16usize;
    let values_start = offsets_start + (value_count * 4);
    let name_offset = values_start + (value_count * 8);

    bytes.extend_from_slice(&(name_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&value_type.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&(value_count as u32).to_le_bytes());
    for index in 0..value_count {
        bytes.extend_from_slice(&((values_start + (index * 8)) as u32).to_le_bytes());
    }
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&utf16_cstr(name));
    bytes
}

fn string_claim(name: &str, value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let offsets_start = 16usize;
    let pointer_start = offsets_start + 4;
    let string_offset = pointer_start + 4;
    let name_offset = string_offset + utf16_cstr(value).len();

    bytes.extend_from_slice(&(name_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&CLAIM_TYPE_STRING.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&(pointer_start as u32).to_le_bytes());
    bytes.extend_from_slice(&(string_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&utf16_cstr(value));
    bytes.extend_from_slice(&utf16_cstr(name));
    bytes
}

fn sid_claim(name: &str, sid: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let offsets_start = 16usize;
    let pointer_start = offsets_start + 4;
    let sid_offset = pointer_start + 4;
    let name_offset = sid_offset + sid.len();

    bytes.extend_from_slice(&(name_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&CLAIM_TYPE_SID.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&(pointer_start as u32).to_le_bytes());
    bytes.extend_from_slice(&(sid_offset as u32).to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes.extend_from_slice(&utf16_cstr(name));
    bytes
}

fn octet_claim(name: &str, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let offsets_start = 16usize;
    let pointer_start = offsets_start + 4;
    let blob_offset = pointer_start + 4;
    let name_offset = blob_offset + 4 + value.len();

    bytes.extend_from_slice(&(name_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&CLAIM_TYPE_OCTET.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&(pointer_start as u32).to_le_bytes());
    bytes.extend_from_slice(&(blob_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
    bytes.extend_from_slice(value);
    bytes.extend_from_slice(&utf16_cstr(name));
    bytes
}




fn sd_with_sacl(owner: &[u8], sacl: &[u8]) -> Vec<u8> {
    let control = SE_SELF_RELATIVE | SE_SACL_PRESENT;
    let mut bytes = vec![0u8; 20];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    let owner_offset = bytes.len() as u32;
    bytes[4..8].copy_from_slice(&owner_offset.to_le_bytes());
    bytes.extend_from_slice(owner);
    let group_offset = bytes.len() as u32;
    bytes[8..12].copy_from_slice(&group_offset.to_le_bytes());
    bytes.extend_from_slice(owner);
    let sacl_offset = bytes.len() as u32;
    bytes[12..16].copy_from_slice(&sacl_offset.to_le_bytes());
    bytes.extend_from_slice(sacl);
    bytes
}

#[test]
fn resource_attributes_use_first_wins_case_insensitive_duplicates() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let sacl = acl_bytes(&[
        resource_attribute_ace(0, &int64_claim("Dept", 1)),
        resource_attribute_ace(0, &int64_claim("dept", 2)),
    ]);
    let sd_bytes = sd_with_sacl(&owner, &sacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let metadata = extract_sacl_metadata(&sd).expect("metadata should extract");

    assert_eq!(metadata.resource_attributes.len(), 1);
    assert_eq!(metadata.resource_attributes[0].name, "Dept");
    assert_eq!(
        metadata.resource_attributes[0].values,
        vec![kacs_core::ClaimValue::Int64(1)]
    );
}

#[test]
fn resource_attributes_extract_supported_value_shapes() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let principal = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 77]);
    let sacl = acl_bytes(&[
        resource_attribute_ace(0, &int64_values_claim("Levels", &[3, 4])),
        resource_attribute_ace(0, &u64_values_claim("Quota", CLAIM_TYPE_UINT64, &[9])),
        resource_attribute_ace(0, &string_claim("Kind", "svc")),
        resource_attribute_ace(0, &u64_values_claim("Enabled", CLAIM_TYPE_BOOLEAN, &[2])),
        resource_attribute_ace(0, &sid_claim("Principal", &principal)),
        resource_attribute_ace(0, &octet_claim("Blob", &[0xde, 0xad])),
    ]);
    let sd_bytes = sd_with_sacl(&owner, &sacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let metadata = extract_sacl_metadata(&sd).expect("metadata should extract");

    assert_eq!(metadata.resource_attributes.len(), 6);
    assert_eq!(metadata.resource_attributes[0].name, "Levels");
    assert_eq!(
        metadata.resource_attributes[0].values,
        vec![ClaimValue::Int64(3), ClaimValue::Int64(4)]
    );
    assert_eq!(metadata.resource_attributes[1].name, "Quota");
    assert_eq!(
        metadata.resource_attributes[1].values,
        vec![ClaimValue::UInt64(9)]
    );
    assert_eq!(metadata.resource_attributes[2].name, "Kind");
    assert_eq!(
        metadata.resource_attributes[2].values,
        vec![ClaimValue::String("svc".into())]
    );
    assert_eq!(metadata.resource_attributes[3].name, "Enabled");
    assert_eq!(
        metadata.resource_attributes[3].values,
        vec![ClaimValue::Boolean(2)]
    );
    assert_eq!(metadata.resource_attributes[4].name, "Principal");
    assert_eq!(
        metadata.resource_attributes[4].values,
        vec![ClaimValue::Sid(principal.into())]
    );
    assert_eq!(metadata.resource_attributes[5].name, "Blob");
    assert_eq!(
        metadata.resource_attributes[5].values,
        vec![ClaimValue::Octet(vec![0xde, 0xad].into())]
    );
}

#[test]
fn scoped_policy_sids_preserve_scan_order() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let first = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 1]);
    let second = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 2]);
    let sacl = acl_bytes(&[
        basic_ace(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, 0, 0, &first),
        resource_attribute_ace(0, &int64_claim("Level", 3)),
        basic_ace(SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, 0, 0, &second),
    ]);
    let sd_bytes = sd_with_sacl(&owner, &sacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let metadata = extract_sacl_metadata(&sd).expect("metadata should extract");

    assert_eq!(metadata.policy_sids.len(), 2);
    assert_eq!(metadata.policy_sids[0].as_bytes(), first.as_slice());
    assert_eq!(metadata.policy_sids[1].as_bytes(), second.as_slice());
}

#[test]
fn malformed_resource_attribute_payload_fails_closed() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let sacl = acl_bytes(&[resource_attribute_ace(0, &[1, 2, 3, 4])]);
    let sd_bytes = sd_with_sacl(&owner, &sacl);
    let err = SecurityDescriptor::parse(&sd_bytes).expect_err("malformed payload must fail");
    assert_eq!(err, KacsError::InvalidClaimFormat("claim entry header"));
}

#[test]
fn resource_attribute_rejects_fqbn_claim_type() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let mut fqbn_claim = int64_claim("Publisher", 1);
    fqbn_claim[4..6].copy_from_slice(&0x0004u16.to_le_bytes());
    let sacl = acl_bytes(&[resource_attribute_ace(0, &fqbn_claim)]);
    let sd_bytes = sd_with_sacl(&owner, &sacl);

    let err = SecurityDescriptor::parse(&sd_bytes).expect_err("FQBN resource claim must fail");

    assert_eq!(err, KacsError::InvalidClaimType(0x0004));
}

#[test]
fn inherit_only_sacl_metadata_aces_are_ignored() {
    let owner = sid_bytes([0, 0, 0, 0, 0, 5], &[18]);
    let policy = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 3]);
    let sacl = acl_bytes(&[
        resource_attribute_ace(INHERIT_ONLY_ACE, &int64_claim("Inherited", 7)),
        basic_ace(
            SYSTEM_SCOPED_POLICY_ID_ACE_TYPE,
            INHERIT_ONLY_ACE,
            0,
            &policy,
        ),
        resource_attribute_ace(0, &int64_claim("Effective", 9)),
    ]);
    let sd_bytes = sd_with_sacl(&owner, &sacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let metadata = extract_sacl_metadata(&sd).expect("metadata should extract");

    assert_eq!(metadata.resource_attributes.len(), 1);
    assert_eq!(metadata.resource_attributes[0].name, "Effective");
    assert!(metadata.policy_sids.is_empty());
}
