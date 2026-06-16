use lcs_core::{
    Guid, KeyCanonicalPathLocation, LcsError, LcsLimits, NIL_GUID,
    validate_key_canonical_path_locations,
};

const PARENT_A: Guid = [0x61; 16];
const PARENT_B: Guid = [0x62; 16];
const KEY_A: Guid = [0x71; 16];
const KEY_B: Guid = [0x72; 16];

fn location(
    guid: Guid,
    parent_guid: Guid,
    child_name: &'static str,
) -> KeyCanonicalPathLocation<'static> {
    KeyCanonicalPathLocation {
        guid,
        parent_guid,
        child_name,
    }
}

#[test]
fn canonical_locations_allow_same_path_with_distinct_key_guids() {
    let limits = LcsLimits::default();
    let locations = [
        location(KEY_A, PARENT_A, "Child"),
        location(KEY_B, PARENT_A, "Child"),
    ];

    assert_eq!(
        validate_key_canonical_path_locations(&limits, &locations),
        Ok(())
    );
}

#[test]
fn canonical_locations_reject_same_guid_at_multiple_paths() {
    let limits = LcsLimits::default();
    let locations = [
        location(KEY_A, PARENT_A, "Child"),
        location(KEY_A, PARENT_B, "Alias"),
    ];

    assert_eq!(
        validate_key_canonical_path_locations(&limits, &locations),
        Err(LcsError::DuplicateTrackedKeyGuid {
            field: "canonical_key_locations",
            index: 1,
        })
    );
}

#[test]
fn canonical_locations_fail_closed_on_malformed_location_fields() {
    let limits = LcsLimits::default();

    assert_eq!(
        validate_key_canonical_path_locations(&limits, &[location(NIL_GUID, PARENT_A, "Child")]),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        validate_key_canonical_path_locations(&limits, &[location(KEY_A, NIL_GUID, "Child")]),
        Err(LcsError::NilParentGuid)
    );
    assert_eq!(
        validate_key_canonical_path_locations(&limits, &[location(KEY_A, PARENT_A, "Bad/Name")]),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );
}
