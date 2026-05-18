use core::cmp::Ordering;

use crate::error::LcsResult;
use crate::string::validate_lcs_str;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CaseFoldRange {
    start: u32,
    end: u32,
    mapped_start: u32,
}

include!("casefold_table.rs");

/// Applies PSD-005 Unicode Simple Case Folding to one scalar value.
pub fn unicode_simple_case_fold(value: char) -> char {
    let codepoint = value as u32;

    if let Some(mapped) = fold_from_ranges(codepoint) {
        return mapped;
    }
    if let Some(mapped) = fold_from_pairs(codepoint) {
        return mapped;
    }
    value
}

/// Compares two decoded LCS strings using PSD-005 Unicode Simple Case Folding.
pub fn casefold_eq(left: &str, right: &str) -> bool {
    let mut left_chars = left.chars();
    let mut right_chars = right.chars();

    loop {
        match (left_chars.next(), right_chars.next()) {
            (Some(left), Some(right)) => {
                if unicode_simple_case_fold(left) != unicode_simple_case_fold(right) {
                    return false;
                }
            }
            (None, None) => return true,
            _ => return false,
        }
    }
}

/// Orders two decoded LCS strings by their folded scalar sequence.
pub fn casefold_cmp(left: &str, right: &str) -> Ordering {
    let mut left_chars = left.chars();
    let mut right_chars = right.chars();

    loop {
        match (left_chars.next(), right_chars.next()) {
            (Some(left), Some(right)) => {
                match unicode_simple_case_fold(left).cmp(&unicode_simple_case_fold(right)) {
                    Ordering::Equal => {}
                    other => return other,
                }
            }
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
        }
    }
}

/// Validates two byte strings as LCS strings, then compares them using the
/// PSD-005 folded identity algorithm.
pub fn casefold_eq_bytes(
    left: &[u8],
    left_field: &'static str,
    right: &[u8],
    right_field: &'static str,
) -> LcsResult<bool> {
    let left = validate_lcs_str(left, left_field)?;
    let right = validate_lcs_str(right, right_field)?;
    Ok(casefold_eq(left, right))
}

/// Tests a decoded string against a fixed sentinel using PSD-005 folding.
pub fn casefold_is(value: &str, sentinel: &str) -> bool {
    casefold_eq(value, sentinel)
}

fn fold_from_ranges(codepoint: u32) -> Option<char> {
    let mut low = 0usize;
    let mut high = CASE_FOLD_RANGES.len();

    while low < high {
        let mid = low + ((high - low) / 2);
        let range = CASE_FOLD_RANGES[mid];
        if codepoint < range.start {
            high = mid;
        } else if codepoint > range.end {
            low = mid + 1;
        } else {
            let mapped = range.mapped_start + (codepoint - range.start);
            return Some(
                char::from_u32(mapped).expect("generated Unicode casefold range target is scalar"),
            );
        }
    }

    None
}

fn fold_from_pairs(codepoint: u32) -> Option<char> {
    let mut low = 0usize;
    let mut high = CASE_FOLD_PAIRS.len();

    while low < high {
        let mid = low + ((high - low) / 2);
        let (source, target) = CASE_FOLD_PAIRS[mid];
        if codepoint < source {
            high = mid;
        } else if codepoint > source {
            low = mid + 1;
        } else {
            return Some(
                char::from_u32(target).expect("generated Unicode casefold pair target is scalar"),
            );
        }
    }

    None
}
