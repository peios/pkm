use core::cmp::Ordering;

use lcs_core::{
    LcsError, LcsLimits, casefold_cmp, casefold_eq, casefold_eq_bytes, is_base_layer_name,
    is_reserved_current_user_name, unicode_simple_case_fold, validate_hive_name_bytes,
};

#[test]
fn folds_ascii_and_selected_status_c_mappings() {
    assert_eq!(unicode_simple_case_fold('A'), 'a');
    assert_eq!(unicode_simple_case_fold('Z'), 'z');
    assert_eq!(unicode_simple_case_fold('\u{212A}'), 'k'); // Kelvin sign.
    assert_eq!(unicode_simple_case_fold('\u{00B5}'), '\u{03BC}'); // Micro sign.
    assert_eq!(unicode_simple_case_fold('\u{017F}'), 's'); // Latin long s.
    assert_eq!(unicode_simple_case_fold('\u{03A3}'), '\u{03C3}'); // Sigma.
    assert_eq!(unicode_simple_case_fold('\u{03C2}'), '\u{03C3}'); // Final sigma.
}

#[test]
fn compares_decoded_strings_with_unicode_simple_casefolding() {
    assert!(casefold_eq("Machine\\System", "machine\\system"));
    assert!(casefold_eq("\u{212A}ey", "key"));
    assert!(casefold_eq("Micro-\u{00B5}", "micro-\u{03BC}"));
    assert!(casefold_eq("Σίσυφος", "σίσυφοσ"));
    assert!(casefold_eq("ẞ", "ß"));

    assert_eq!(casefold_cmp("A", "a"), Ordering::Equal);
    assert_eq!(casefold_cmp("A", "b"), Ordering::Less);
    assert_eq!(casefold_cmp("B", "a"), Ordering::Greater);
}

#[test]
fn excludes_full_and_turkic_casefold_mappings() {
    assert!(!casefold_eq("Maße", "MASSE"));
    assert!(!casefold_eq("İ", "i"));
    assert_eq!(unicode_simple_case_fold('İ'), 'İ');
}

#[test]
fn does_not_perform_unicode_normalization() {
    assert!(!casefold_eq("\u{00E9}", "e\u{0301}"));
    assert!(casefold_eq("\u{00C9}", "\u{00E9}"));
}

#[test]
fn byte_wrappers_validate_before_comparison() {
    assert_eq!(
        casefold_eq_bytes("RoleA".as_bytes(), "left", b"rolea", "right"),
        Ok(true)
    );
    assert_eq!(
        casefold_eq_bytes(&[0xff], "left", b"rolea", "right"),
        Err(LcsError::InvalidUtf8 { field: "left" })
    );
    assert_eq!(
        casefold_eq_bytes(b"role\0a", "left", b"rolea", "right"),
        Err(LcsError::NullByte { field: "left" })
    );
}

#[test]
fn reserved_sentinel_detection_uses_unicode_folded_identity() {
    let limits = LcsLimits::default();

    assert!(is_reserved_current_user_name("CurrentU\u{017F}er"));
    assert_eq!(
        validate_hive_name_bytes("CurrentU\u{017F}er".as_bytes(), &limits),
        Err(LcsError::ReservedHiveName)
    );
    assert!(is_base_layer_name("ba\u{017F}e"));
}
