use kacs_core::{KacsError, Sid};

fn sid_bytes(sub_authorities: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + (sub_authorities.len() * 4));
    bytes.push(1);
    bytes.push(sub_authorities.len() as u8);
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, 5]);
    for sub_authority in sub_authorities {
        bytes.extend_from_slice(&sub_authority.to_le_bytes());
    }
    bytes
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
    assert_eq!(sid.as_bytes(), bytes.as_slice());
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
