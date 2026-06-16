use crate::common::{sid};
use lcs_core::sid_bytes_equal;


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
