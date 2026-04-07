use kacs_core::{
    parse_claim_attribute_array, parse_claim_attribute_entry, ClaimAttribute, ClaimValue,
    KacsError, CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE, CLAIM_TYPE_BOOLEAN, CLAIM_TYPE_INT64,
    CLAIM_TYPE_OCTET, CLAIM_TYPE_STRING,
};

fn utf16_cstr(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for unit in value.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes
}

fn int64_claim(name: &str, values: &[i64], flags: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    let value_count = values.len();
    let offsets_start = 16usize;
    let values_start = offsets_start + (value_count * 4);
    let name_offset = values_start + (value_count * 8);

    bytes.extend_from_slice(&(name_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&CLAIM_TYPE_INT64.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&(value_count as u32).to_le_bytes());

    for index in 0..value_count {
        let offset = values_start + (index * 8);
        bytes.extend_from_slice(&(offset as u32).to_le_bytes());
    }
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&utf16_cstr(name));
    bytes
}

fn string_claim(name: &str, value: &str, flags: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    let offsets_start = 16usize;
    let pointer_start = offsets_start + 4;
    let string_offset = pointer_start + 4;
    let name_offset = string_offset + utf16_cstr(value).len();

    bytes.extend_from_slice(&(name_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&CLAIM_TYPE_STRING.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&(pointer_start as u32).to_le_bytes());
    bytes.extend_from_slice(&(string_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&utf16_cstr(value));
    bytes.extend_from_slice(&utf16_cstr(name));
    bytes
}

fn boolean_claim(name: &str, value: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    let offsets_start = 16usize;
    let values_start = offsets_start + 4;
    let name_offset = values_start + 8;

    bytes.extend_from_slice(&(name_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&CLAIM_TYPE_BOOLEAN.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&(values_start as u32).to_le_bytes());
    bytes.extend_from_slice(&(if value { 1u64 } else { 0u64 }).to_le_bytes());
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

#[test]
fn parses_int64_claim_entry() {
    let bytes = int64_claim("Clearance", &[3, 4], 0);

    let claim = parse_claim_attribute_entry(&bytes).expect("claim should parse");

    assert_eq!(
        claim,
        ClaimAttribute {
            name: "Clearance".into(),
            flags: 0,
            values: vec![ClaimValue::Int64(3), ClaimValue::Int64(4)],
        }
    );
}

#[test]
fn parses_string_claim_entry_with_case_sensitive_flag() {
    let bytes = string_claim(
        "Department",
        "Finance",
        CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE,
    );

    let claim = parse_claim_attribute_entry(&bytes).expect("claim should parse");

    assert_eq!(
        claim,
        ClaimAttribute {
            name: "Department".into(),
            flags: CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE,
            values: vec![ClaimValue::String("Finance".into())],
        }
    );
}

#[test]
fn parses_length_prefixed_claim_array() {
    let first = int64_claim("Score", &[7], 0);
    let second = boolean_claim("Mfa", true);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(first.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&first);
    bytes.extend_from_slice(&(second.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&second);

    let claims = parse_claim_attribute_array(&bytes).expect("claim array should parse");

    assert_eq!(claims.len(), 2);
    assert_eq!(claims[0].name, "Score");
    assert_eq!(claims[0].values, vec![ClaimValue::Int64(7)]);
    assert_eq!(claims[1].name, "Mfa");
    assert_eq!(claims[1].values, vec![ClaimValue::Boolean(true)]);
}

#[test]
fn malformed_nested_offset_is_rejected() {
    let mut bytes = octet_claim("Blob", &[1, 2, 3]);
    bytes[16..20].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());

    let err = parse_claim_attribute_entry(&bytes).expect_err("invalid nested offset must fail");
    assert_eq!(err, KacsError::InvalidClaimFormat("claim slice length"));
}

#[test]
fn unsupported_claim_type_is_rejected() {
    let mut bytes = int64_claim("Bad", &[1], 0);
    bytes[4..6].copy_from_slice(&0x0004u16.to_le_bytes());

    let err = parse_claim_attribute_entry(&bytes).expect_err("unsupported type must fail");
    assert_eq!(err, KacsError::InvalidClaimType(0x0004));
}
