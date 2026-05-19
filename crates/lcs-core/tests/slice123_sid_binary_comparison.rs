use lcs_core::sid_bytes_equal;

fn sid(authority: u8, subauths: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + subauths.len() * 4);
    bytes.push(1);
    bytes.push(subauths.len() as u8);
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, authority]);
    for subauth in subauths {
        bytes.extend_from_slice(&subauth.to_le_bytes());
    }
    bytes
}

#[test]
fn sid_comparison_accepts_exact_byte_match() {
    let system = sid(5, &[18]);
    let same_system = sid(5, &[18]);

    assert!(sid_bytes_equal(&system, &same_system));
}

#[test]
fn sid_comparison_rejects_different_lengths() {
    let base = sid(5, &[32]);
    let child = sid(5, &[32, 544]);

    assert!(!sid_bytes_equal(&base, &child));
    assert!(!sid_bytes_equal(&child, &base));
}

#[test]
fn sid_comparison_rejects_single_byte_difference() {
    let administrators = sid(5, &[32, 544]);
    let mut altered = administrators.clone();
    let last = altered.len() - 1;
    altered[last] ^= 0x01;

    assert!(!sid_bytes_equal(&administrators, &altered));
}

#[test]
fn sid_comparison_does_not_parse_or_normalize() {
    let malformed = [0x02, 0xFF, 0xAA, 0x00];
    let same_malformed = [0x02, 0xFF, 0xAA, 0x00];
    let different_malformed = [0x02, 0xFF, 0xAA, 0x01];

    assert!(sid_bytes_equal(&malformed, &same_malformed));
    assert!(!sid_bytes_equal(&malformed, &different_malformed));
}
