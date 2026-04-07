use kacs_core::{
    extract_sacl_metadata, KacsError, SecurityDescriptor, SE_SACL_PRESENT, SE_SELF_RELATIVE,
};

const SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE: u8 = 0x12;
const SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: u8 = 0x13;

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

fn sd_with_sacl(owner: &[u8], sacl: &[u8]) -> Vec<u8> {
    let control = SE_SELF_RELATIVE | SE_SACL_PRESENT;
    let mut bytes = vec![0u8; 20];
    bytes[0] = 1;
    bytes[2..4].copy_from_slice(&control.to_le_bytes());
    bytes[4..8].copy_from_slice(&20u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&20u32.to_le_bytes());
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
    let sacl = acl_bytes(&[resource_attribute_ace(0, &[1, 2, 3])]);
    let sd_bytes = sd_with_sacl(&owner, &sacl);
    let sd = SecurityDescriptor::parse(&sd_bytes).expect("sd should parse");

    let err = extract_sacl_metadata(&sd).expect_err("malformed payload must fail");
    assert_eq!(err, KacsError::InvalidClaimFormat("claim entry header"));
}
