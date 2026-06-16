use lcs_core::{
    EnumSubkeyOutcome, EnumSubkeyResult, EnumValueOutcome, EnumValueResult, LinuxErrno,
    QueryValueOutcome, QueryValueResult, RegistryValueType, enum_subkey_outcome_errno,
    enum_subkey_result_at, enum_value_outcome_errno, enum_value_result_at,
    query_value_outcome_errno,
};

#[test]
fn query_value_not_found_projects_to_linux_enoent() {
    assert_eq!(
        query_value_outcome_errno(&QueryValueOutcome::NotFound),
        Some(LinuxErrno::Enoent)
    );
}

#[test]
fn query_value_found_has_no_errno() {
    let outcome = QueryValueOutcome::Found(QueryValueResult {
        value_type: RegistryValueType::Sz,
        data: b"value",
        data_len: 5,
        sequence: 7,
        layer: "base",
        layer_len: 4,
    });

    assert_eq!(query_value_outcome_errno(&outcome), None);
}

#[test]
fn enum_value_index_past_end_projects_to_linux_enoent() {
    let outcome = enum_value_result_at(&[], 0);

    assert_eq!(outcome, EnumValueOutcome::NotFound);
    assert_eq!(enum_value_outcome_errno(&outcome), Some(LinuxErrno::Enoent));
}

#[test]
fn enum_value_found_has_no_errno() {
    let outcome = EnumValueOutcome::Found(EnumValueResult {
        name: "Name",
        name_len: 4,
        value_type: RegistryValueType::Dword,
        data: &[1, 0, 0, 0],
        data_len: 4,
    });

    assert_eq!(enum_value_outcome_errno(&outcome), None);
}

#[test]
fn enum_subkey_index_past_end_projects_to_linux_enoent() {
    let outcome = enum_subkey_result_at(&[], 0);

    assert_eq!(outcome, EnumSubkeyOutcome::NotFound);
    assert_eq!(
        enum_subkey_outcome_errno(&outcome),
        Some(LinuxErrno::Enoent)
    );
}

#[test]
fn enum_subkey_found_has_no_errno() {
    let outcome = EnumSubkeyOutcome::Found(EnumSubkeyResult {
        name: "Child",
        name_len: 5,
        last_write_time: 99,
        subkey_count: 1,
        value_count: 2,
    });

    assert_eq!(enum_subkey_outcome_errno(&outcome), None);
}
