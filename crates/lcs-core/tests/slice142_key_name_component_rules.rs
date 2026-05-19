use lcs_core::{
    Guid, KEY_CREATE_SUB_KEY, KeyCreateRequest, KeyParent, KeyRecordView, LcsError, LcsLimits,
    PathKind, validate_key_component_bytes, validate_key_create_request, validate_key_record,
    validate_registry_path_str,
};

const PARENT_GUID: Guid = [0x22; 16];
const CHILD_GUID: Guid = [0x23; 16];

fn limits() -> LcsLimits {
    LcsLimits::default()
}

fn create_request(child_name: &'static str) -> KeyCreateRequest<'static> {
    KeyCreateRequest {
        parent_guid: PARENT_GUID,
        parent_is_volatile: false,
        parent_granted_access: KEY_CREATE_SUB_KEY,
        child_name,
        child_guid: CHILD_GUID,
        flags: 0,
        caller_has_tcb_or_admin: false,
    }
}

#[test]
fn key_components_accept_valid_utf8_and_reject_forbidden_bytes() {
    let limits = limits();

    assert_eq!(
        validate_key_component_bytes("Service Name".as_bytes(), &limits),
        Ok("Service Name")
    );
    assert_eq!(
        validate_key_component_bytes("Stra\u{00dF}e".as_bytes(), &limits),
        Ok("Stra\u{00dF}e")
    );
    assert_eq!(
        validate_key_component_bytes(b"", &limits),
        Err(LcsError::EmptyString {
            field: "key_component",
        })
    );
    assert_eq!(
        validate_key_component_bytes(b"Bad\\Name", &limits),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );
    assert_eq!(
        validate_key_component_bytes(b"Bad/Name", &limits),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );
    assert_eq!(
        validate_key_component_bytes(b"Bad\0Name", &limits),
        Err(LcsError::NullByte {
            field: "key_component",
        })
    );
}

#[test]
fn key_records_and_create_requests_reuse_component_validation() {
    let limits = limits();

    assert_eq!(
        validate_key_record(
            &limits,
            &KeyRecordView {
                guid: CHILD_GUID,
                name: "Service Name",
                parent: KeyParent::Parent(PARENT_GUID),
                volatile: false,
                symlink: false,
            },
        )
        .unwrap()
        .name,
        "Service Name"
    );
    assert_eq!(
        validate_key_record(
            &limits,
            &KeyRecordView {
                guid: CHILD_GUID,
                name: "Bad/Name",
                parent: KeyParent::Parent(PARENT_GUID),
                volatile: false,
                symlink: false,
            },
        ),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );

    assert_eq!(
        validate_key_create_request(&limits, &create_request("Stra\u{00dF}e"))
            .unwrap()
            .name,
        "Stra\u{00dF}e"
    );
    assert_eq!(
        validate_key_create_request(&limits, &create_request("Bad\\Name")),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );
}

#[test]
fn paths_normalize_forward_separators_and_reject_empty_components() {
    let limits = limits();

    let path =
        validate_registry_path_str("Machine/System/Service Name", PathKind::Absolute, &limits)
            .expect("valid slash-separated path should validate");
    assert_eq!(path.component_count, 3);
    assert_eq!(path.first_component, "Machine");
    assert_eq!(path.final_component, "Service Name");
    assert!(path.used_forward_separator);

    assert_eq!(
        validate_registry_path_str("Machine//System", PathKind::Absolute, &limits),
        Err(LcsError::EmptyPathComponent)
    );
    assert_eq!(
        validate_registry_path_str("Machine\\\\System", PathKind::Absolute, &limits),
        Err(LcsError::EmptyPathComponent)
    );
    assert_eq!(
        validate_registry_path_str("Machine/System/", PathKind::Absolute, &limits),
        Err(LcsError::TrailingPathSeparator)
    );
    assert_eq!(
        validate_registry_path_str("Machine\0System", PathKind::Absolute, &limits),
        Err(LcsError::NullByte { field: "path" })
    );
}
