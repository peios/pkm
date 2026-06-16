use lcs_core::{
    Guid, LcsError, LcsLimits, NIL_GUID, SourceRegistrationHive, SourceRegistrationRequest,
    validate_source_registration,
};

const ROOT_GUID: Guid = [0x31; 16];

fn limits() -> LcsLimits {
    LcsLimits::default()
}

fn global_hive<'a>(name: &'a str, root_guid: Guid) -> SourceRegistrationHive<'a> {
    SourceRegistrationHive {
        name,
        root_guid,
        flags: 0,
        scope_guid: NIL_GUID,
    }
}

fn request<'a>(
    hives: &'a [SourceRegistrationHive<'a>],
    max_sequence: u64,
) -> SourceRegistrationRequest<'a> {
    SourceRegistrationRequest {
        hives,
        max_sequence,
        caller_has_tcb: true,
    }
}

#[test]
fn source_registration_rejects_hive_names_that_are_not_key_components() {
    let limits = limits();

    assert_eq!(
        validate_source_registration(&limits, &[], &request(&[global_hive("", ROOT_GUID)], 0)),
        Err(LcsError::EmptyString { field: "hive_name" })
    );
    assert_eq!(
        validate_source_registration(
            &limits,
            &[],
            &request(&[global_hive("Bad/Name", ROOT_GUID)], 0),
        ),
        Err(LcsError::NameContainsSeparator { field: "hive_name" })
    );
    assert_eq!(
        validate_source_registration(
            &limits,
            &[],
            &request(&[global_hive("Bad\\Name", ROOT_GUID)], 0),
        ),
        Err(LcsError::NameContainsSeparator { field: "hive_name" })
    );
    assert_eq!(
        validate_source_registration(
            &limits,
            &[],
            &request(&[global_hive("Bad\0Name", ROOT_GUID)], 0),
        ),
        Err(LcsError::NullByte { field: "hive_name" })
    );
}

#[test]
fn source_registration_rejects_current_user_hive_with_folded_identity() {
    let limits = limits();

    assert_eq!(
        validate_source_registration(
            &limits,
            &[],
            &request(&[global_hive("CurrentUser", ROOT_GUID)], 0),
        ),
        Err(LcsError::ReservedHiveName)
    );
    assert_eq!(
        validate_source_registration(
            &limits,
            &[],
            &request(&[global_hive("currentuser", ROOT_GUID)], 0),
        ),
        Err(LcsError::ReservedHiveName)
    );
    assert_eq!(
        validate_source_registration(
            &limits,
            &[],
            &request(&[global_hive("CurrentU\u{017F}er", ROOT_GUID)], 0),
        ),
        Err(LcsError::ReservedHiveName)
    );
}

#[test]
fn source_registration_rejects_invalid_utf8_hive_names_before_identity_checks() {
    let limits = limits();

    assert_eq!(
        lcs_core::validate_hive_name_bytes(&[0xff], &limits),
        Err(LcsError::InvalidUtf8 { field: "hive_name" })
    );
}

#[test]
fn source_registration_rejects_hive_names_above_component_limit() {
    let mut limits = limits();
    limits.max_path_component_length = "Machine".len() - 1;

    assert_eq!(
        validate_source_registration(
            &limits,
            &[],
            &request(&[global_hive("Machine", ROOT_GUID)], 0),
        ),
        Err(LcsError::NameTooLong {
            field: "hive_name",
            len: "Machine".len(),
            max: "Machine".len() - 1,
        })
    );
}
