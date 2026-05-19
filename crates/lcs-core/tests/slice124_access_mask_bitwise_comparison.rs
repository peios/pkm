use lcs_core::{
    KEY_CREATE_SUB_KEY, KEY_NOTIFY, KEY_QUERY_VALUE, KEY_READ, KEY_SET_VALUE, access_mask_includes,
    registry_fd_has_right,
};

#[test]
fn access_mask_inclusion_accepts_exact_and_superset_matches() {
    assert!(access_mask_includes(KEY_QUERY_VALUE, KEY_QUERY_VALUE));
    assert!(access_mask_includes(
        KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_NOTIFY,
        KEY_QUERY_VALUE | KEY_NOTIFY
    ));
}

#[test]
fn access_mask_inclusion_rejects_partial_and_absent_matches() {
    assert!(!access_mask_includes(
        KEY_QUERY_VALUE | KEY_NOTIFY,
        KEY_QUERY_VALUE | KEY_SET_VALUE
    ));
    assert!(!access_mask_includes(KEY_NOTIFY, KEY_SET_VALUE));
}

#[test]
fn access_mask_inclusion_uses_the_raw_psd_005_formula_for_zero_required_mask() {
    assert!(access_mask_includes(0, 0));
    assert!(access_mask_includes(KEY_SET_VALUE, 0));
}

#[test]
fn registry_fd_right_checks_delegate_to_bitwise_inclusion() {
    assert!(registry_fd_has_right(
        KEY_READ | KEY_CREATE_SUB_KEY,
        KEY_QUERY_VALUE | KEY_CREATE_SUB_KEY
    ));
    assert!(!registry_fd_has_right(
        KEY_READ,
        KEY_QUERY_VALUE | KEY_CREATE_SUB_KEY
    ));
}
