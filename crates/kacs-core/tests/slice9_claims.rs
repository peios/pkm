use kacs_core::{
    parse_claim_attribute_array, parse_claim_attribute_entry, ClaimAttribute, ClaimValue,
    KacsError, CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE, CLAIM_TYPE_BOOLEAN, CLAIM_TYPE_INT64,
    CLAIM_TYPE_OCTET, CLAIM_TYPE_SID, CLAIM_TYPE_STRING, CLAIM_TYPE_UINT64,
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

fn uint64_claim(name: &str, values: &[u64], flags: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    let value_count = values.len();
    let offsets_start = 16usize;
    let values_start = offsets_start + (value_count * 4);
    let name_offset = values_start + (value_count * 8);

    bytes.extend_from_slice(&(name_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&CLAIM_TYPE_UINT64.to_le_bytes());
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

fn boolean_claim(name: &str, value: u64) -> Vec<u8> {
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
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes.extend_from_slice(&utf16_cstr(name));
    bytes
}

fn empty_claim(name: &str, value_type: u16, flags: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    let name_offset = 16usize;

    bytes.extend_from_slice(&(name_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&value_type.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&utf16_cstr(name));
    bytes
}

fn string_claim_with_unterminated_value(name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let pointer_start = 20usize;
    let name_offset = 24usize;
    let string_offset = name_offset + utf16_cstr(name).len();

    bytes.extend_from_slice(&(name_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&CLAIM_TYPE_STRING.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&(pointer_start as u32).to_le_bytes());
    bytes.extend_from_slice(&(string_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&utf16_cstr(name));
    bytes.extend_from_slice(&0x0041u16.to_le_bytes());
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

fn sid_claim_with_trailing_data(name: &str, sid: &[u8], trailing: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let offsets_start = 16usize;
    let pointer_start = offsets_start + 4;
    let sid_offset = pointer_start + 4;
    let name_offset = sid_offset + sid.len() + trailing.len();

    bytes.extend_from_slice(&(name_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&CLAIM_TYPE_SID.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&(pointer_start as u32).to_le_bytes());
    bytes.extend_from_slice(&(sid_offset as u32).to_le_bytes());
    bytes.extend_from_slice(sid);
    bytes.extend_from_slice(trailing);
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
            value_type: 0x0001,
            flags: 0,
            values: vec![ClaimValue::Int64(3), ClaimValue::Int64(4)].into(),
        }
    );
}

#[test]
fn parses_uint64_claim_entry() {
    let bytes = uint64_claim("Quota", &[9, u64::MAX], 0);

    let claim = parse_claim_attribute_entry(&bytes).expect("claim should parse");

    assert_eq!(
        claim,
        ClaimAttribute {
            name: "Quota".into(),
            value_type: CLAIM_TYPE_UINT64,
            flags: 0,
            values: vec![ClaimValue::UInt64(9), ClaimValue::UInt64(u64::MAX)].into(),
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
            value_type: 0x0003,
            flags: CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE,
            values: vec![ClaimValue::String("Finance".into())].into(),
        }
    );
}

#[test]
fn nonzero_reserved_field_is_ignored() {
    let mut bytes = int64_claim("Reserved", &[11], 0);
    bytes[6..8].copy_from_slice(&0xfeedu16.to_le_bytes());

    let claim = parse_claim_attribute_entry(&bytes).expect("claim should parse");

    assert_eq!(claim.name, "Reserved");
    assert_eq!(claim.value_type, CLAIM_TYPE_INT64);
    assert_eq!(claim.values, vec![ClaimValue::Int64(11)]);
}

#[test]
fn unknown_claim_flags_are_preserved_without_parser_semantics() {
    let unknown_flags = 0x8000_0040u32;
    let bytes = uint64_claim("OpaqueFlags", &[5], unknown_flags);

    let claim = parse_claim_attribute_entry(&bytes).expect("claim should parse");

    assert_eq!(claim.name, "OpaqueFlags");
    assert_eq!(claim.flags, unknown_flags);
    assert_eq!(claim.values, vec![ClaimValue::UInt64(5)]);
}

#[test]
fn unterminated_claim_name_is_rejected() {
    let mut bytes = int64_claim("NoTerminator", &[1], 0);
    bytes.truncate(bytes.len() - 2);

    let err = parse_claim_attribute_entry(&bytes).expect_err("unterminated name must fail");

    assert_eq!(
        err,
        KacsError::InvalidClaimFormat("unterminated utf16 string")
    );
}

#[test]
fn unterminated_string_value_is_rejected() {
    let bytes = string_claim_with_unterminated_value("BadValue");

    let err = parse_claim_attribute_entry(&bytes).expect_err("unterminated value must fail");

    assert_eq!(
        err,
        KacsError::InvalidClaimFormat("unterminated utf16 string")
    );
}

#[test]
fn malformed_sid_claim_value_is_rejected() {
    let invalid_sid = [2, 0, 0, 0, 0, 0, 0, 5];
    let bytes = sid_claim_with_trailing_data("BrokenSid", &invalid_sid, &[]);

    let err = parse_claim_attribute_entry(&bytes).expect_err("invalid SID must fail");

    assert_eq!(err, KacsError::InvalidSidRevision(2));
}

#[test]
fn zero_value_count_claim_entry_is_valid() {
    let bytes = empty_claim("Empty", CLAIM_TYPE_STRING, 0);

    let claim = parse_claim_attribute_entry(&bytes).expect("empty claim should parse");

    assert_eq!(
        claim,
        ClaimAttribute {
            name: "Empty".into(),
            value_type: CLAIM_TYPE_STRING,
            flags: 0,
            values: Vec::new().into(),
        }
    );
}

#[test]
fn parses_length_prefixed_claim_array() {
    let first = int64_claim("Score", &[7], 0);
    let second = boolean_claim("Mfa", 1);
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
    assert_eq!(claims[1].values, vec![ClaimValue::Boolean(1)]);
}

#[test]
fn claim_array_rejects_zero_entry_length() {
    let bytes = 0u32.to_le_bytes();

    let err = parse_claim_attribute_array(&bytes).expect_err("zero entry length must fail");

    assert_eq!(
        err,
        KacsError::InvalidClaimFormat("zero-length claim entry")
    );
}

#[test]
fn claim_array_rejects_overlong_entry_length() {
    let first = int64_claim("Score", &[7], 0);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&((first.len() + 1) as u32).to_le_bytes());
    bytes.extend_from_slice(&first);

    let err = parse_claim_attribute_array(&bytes).expect_err("overlong entry length must fail");

    assert_eq!(
        err,
        KacsError::InvalidClaimFormat("claim array entry length")
    );
}

#[test]
fn parses_boolean_claim_entry_preserving_raw_u64() {
    let bytes = boolean_claim("Mfa", 2);

    let claim = parse_claim_attribute_entry(&bytes).expect("claim should parse");

    assert_eq!(
        claim,
        ClaimAttribute {
            name: "Mfa".into(),
            value_type: CLAIM_TYPE_BOOLEAN,
            flags: 0,
            values: vec![ClaimValue::Boolean(2)].into(),
        }
    );
}

#[test]
fn malformed_nested_offset_is_rejected() {
    let mut bytes = octet_claim("Blob", &[1, 2, 3]);
    bytes[16..20].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());

    let err = parse_claim_attribute_entry(&bytes).expect_err("invalid nested offset must fail");
    assert_eq!(err, KacsError::InvalidClaimFormat("claim slice length"));
}

#[test]
fn parses_sid_claim_when_sid_is_not_at_entry_tail() {
    let sid = sid_bytes([0, 0, 0, 0, 0, 5], &[21, 17000]);
    let bytes = sid_claim_with_trailing_data("Owner", &sid, &[0xaa, 0xbb, 0xcc, 0xdd]);

    let claim = parse_claim_attribute_entry(&bytes).expect("sid claim should parse");

    assert_eq!(
        claim,
        ClaimAttribute {
            name: "Owner".into(),
            value_type: 0x0005,
            flags: 0,
            values: vec![ClaimValue::Sid(sid.into())].into(),
        }
    );
}

#[test]
fn unsupported_claim_type_is_rejected() {
    let mut bytes = int64_claim("Bad", &[1], 0);
    bytes[4..6].copy_from_slice(&0x0004u16.to_le_bytes());

    let err = parse_claim_attribute_entry(&bytes).expect_err("unsupported type must fail");
    assert_eq!(err, KacsError::InvalidClaimType(0x0004));
}

#[test]
fn oversized_value_count_is_rejected_before_allocation() {
    let mut bytes = vec![0u8; 16];
    bytes[0..4].copy_from_slice(&16u32.to_le_bytes());
    bytes[4..6].copy_from_slice(&CLAIM_TYPE_INT64.to_le_bytes());
    bytes[12..16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    let err = parse_claim_attribute_entry(&bytes).expect_err("oversized value_count must fail");
    assert_eq!(err, KacsError::InvalidClaimFormat("claim value offsets"));
}
