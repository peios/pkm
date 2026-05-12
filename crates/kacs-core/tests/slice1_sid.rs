use kacs_core::{
    KacsError, Sid, SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_INTEGRITY,
    SE_GROUP_INTEGRITY_ENABLED, SE_GROUP_LOGON_ID, SE_GROUP_MANDATORY, SE_GROUP_OWNER,
    SE_GROUP_RESOURCE, SE_GROUP_USE_FOR_DENY_ONLY,
};

fn sid_bytes(sub_authorities: &[u32]) -> Vec<u8> {
    sid_bytes_with_authority([0, 0, 0, 0, 0, 5], sub_authorities)
}

fn sid_bytes_with_authority(authority: [u8; 6], sub_authorities: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + (sub_authorities.len() * 4));
    bytes.push(1);
    bytes.push(sub_authorities.len() as u8);
    bytes.extend_from_slice(&authority);
    for sub_authority in sub_authorities {
        bytes.extend_from_slice(&sub_authority.to_le_bytes());
    }
    bytes
}

#[test]
fn group_attribute_constants_match_spec_catalog() {
    assert_eq!(SE_GROUP_MANDATORY, 0x0000_0001);
    assert_eq!(SE_GROUP_ENABLED_BY_DEFAULT, 0x0000_0002);
    assert_eq!(SE_GROUP_ENABLED, 0x0000_0004);
    assert_eq!(SE_GROUP_OWNER, 0x0000_0008);
    assert_eq!(SE_GROUP_USE_FOR_DENY_ONLY, 0x0000_0010);
    assert_eq!(SE_GROUP_INTEGRITY, 0x0000_0020);
    assert_eq!(SE_GROUP_INTEGRITY_ENABLED, 0x0000_0040);
    assert_eq!(SE_GROUP_LOGON_ID, 0xC000_0000);
    assert_eq!(SE_GROUP_RESOURCE, 0x2000_0000);
}

#[test]
fn parses_valid_sid_and_exposes_binary_fields() {
    let bytes = sid_bytes(&[21, 32, 544]);
    let sid = Sid::parse(&bytes).expect("valid sid should parse");

    assert_eq!(sid.revision(), 1);
    assert_eq!(sid.sub_authority_count(), 3);
    assert_eq!(sid.identifier_authority(), [0, 0, 0, 0, 0, 5]);
    assert_eq!(sid.sub_authority(0), Some(21));
    assert_eq!(sid.sub_authority(1), Some(32));
    assert_eq!(sid.sub_authority(2), Some(544));
    assert_eq!(sid.sub_authority(3), None);
    assert_eq!(sid.relative_identifier(), Some(544));
    assert_eq!(sid.as_bytes(), bytes.as_slice());
}

#[test]
fn zero_subauthority_sid_has_no_relative_identifier() {
    let bytes = sid_bytes(&[]);
    let sid = Sid::parse(&bytes).expect("valid sid should parse");

    assert_eq!(sid.sub_authority_count(), 0);
    assert_eq!(sid.as_bytes().len(), Sid::MIN_SIZE);
    assert_eq!(sid.sub_authority(0), None);
    assert_eq!(sid.relative_identifier(), None);
}

#[test]
fn preserves_full_six_byte_identifier_authority() {
    let authority = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    let bytes = sid_bytes_with_authority(authority, &[0x1122_3344]);
    let sid = Sid::parse(&bytes).expect("valid sid should parse");

    assert_eq!(sid.identifier_authority(), authority);
    assert_eq!(sid.as_bytes()[2..8], authority);
}

#[test]
fn formats_sid_string_with_revision_authority_and_subauthorities() {
    let bytes = sid_bytes(&[21, 32, 544]);
    let sid = Sid::parse(&bytes).expect("valid sid should parse");

    assert_eq!(sid.to_string(), "S-1-5-21-32-544");
}

#[test]
fn formats_zero_subauthority_sid_string() {
    let bytes = sid_bytes(&[]);
    let sid = Sid::parse(&bytes).expect("valid sid should parse");

    assert_eq!(sid.to_string(), "S-1-5");
}

#[test]
fn formats_zero_high_bytes_authority_as_decimal_lower_four_bytes() {
    let bytes = sid_bytes_with_authority([0, 0, 0x12, 0x34, 0x56, 0x78], &[]);
    let sid = Sid::parse(&bytes).expect("valid sid should parse");

    assert_eq!(sid.to_string(), "S-1-305419896");
}

#[test]
fn formats_nonzero_high_bytes_authority_as_prefixed_padded_hex() {
    let bytes = sid_bytes_with_authority([0x01, 0x02, 0x03, 0x04, 0x05, 0x06], &[]);
    let sid = Sid::parse(&bytes).expect("valid sid should parse");

    assert_eq!(sid.to_string(), "S-1-0x010203040506");
}

#[test]
fn formats_subauthorities_as_unsigned_decimal_values() {
    let bytes = sid_bytes(&[0, 2_147_483_648, u32::MAX]);
    let sid = Sid::parse(&bytes).expect("valid sid should parse");

    assert_eq!(sid.to_string(), "S-1-5-0-2147483648-4294967295");
}

#[test]
fn compares_sids_by_exact_binary_encoding() {
    let a_bytes = sid_bytes(&[21, 32, 544]);
    let b_bytes = sid_bytes(&[21, 32, 544]);
    let c_bytes = sid_bytes(&[21, 32, 545]);

    let a = Sid::parse(&a_bytes).expect("valid sid should parse");
    let b = Sid::parse(&b_bytes).expect("valid sid should parse");
    let c = Sid::parse(&c_bytes).expect("valid sid should parse");

    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn rejects_invalid_revision() {
    let mut bytes = sid_bytes(&[18]);
    bytes[0] = 2;

    let err = Sid::parse(&bytes).expect_err("invalid revision must fail");
    assert_eq!(err, KacsError::InvalidSidRevision(2));
}

#[test]
fn rejects_sub_authority_count_above_fifteen() {
    let mut bytes = vec![1, 16, 0, 0, 0, 0, 0, 5];
    bytes.extend_from_slice(&0u32.to_le_bytes());

    let err = Sid::parse(&bytes).expect_err("count above fifteen must fail");
    assert_eq!(err, KacsError::InvalidSidSubAuthorityCount(16));
}

#[test]
fn rejects_length_mismatch_for_exact_parse() {
    let mut bytes = sid_bytes(&[21, 32]);
    bytes.pop();

    let err = Sid::parse(&bytes).expect_err("length mismatch must fail");
    assert_eq!(
        err,
        KacsError::InvalidSidLength {
            expected: 16,
            actual: 15,
        }
    );
}

#[test]
fn parses_prefix_without_consuming_trailing_bytes() {
    let sid = sid_bytes(&[18]);
    let mut buffer = sid.clone();
    buffer.extend_from_slice(b"tail");

    let (parsed, consumed) = Sid::parse_prefix(&buffer).expect("prefix parse should succeed");

    assert_eq!(consumed, sid.len());
    assert_eq!(parsed.as_bytes(), sid.as_slice());
}
