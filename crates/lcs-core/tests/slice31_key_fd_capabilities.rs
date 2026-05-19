use lcs_core::{
    GENERIC_READ, KEY_READ, KEY_SET_VALUE, KeyFdDelegationPlan, KeyFdOpenView, KeyWatchState,
    LcsError, LcsLimits, MAXIMUM_ALLOWED, NIL_GUID, key_fd_granted_access_allows,
    plan_key_fd_delegation, validate_key_fd_open_view, validate_registry_granted_access,
};

const ROOT: [u8; 16] = [0x11; 16];
const CHILD: [u8; 16] = [0x22; 16];

fn fd_view<'a>(
    resolved_path: &'a [&'a str],
    ancestor_guids: &'a [[u8; 16]],
    granted_access: u32,
) -> KeyFdOpenView<'a> {
    KeyFdOpenView {
        key_guid: CHILD,
        granted_access,
        resolved_path,
        ancestor_guids,
        watch_state: KeyWatchState {
            armed: false,
            orphaned: false,
        },
    }
}

#[test]
fn granted_access_masks_are_concrete_registry_rights_only() {
    assert_eq!(validate_registry_granted_access(KEY_READ), Ok(KEY_READ));
    assert_eq!(
        validate_registry_granted_access(KEY_READ | GENERIC_READ),
        Err(LcsError::UnknownAccessBits(GENERIC_READ))
    );
    assert_eq!(
        validate_registry_granted_access(MAXIMUM_ALLOWED),
        Err(LcsError::UnknownAccessBits(MAXIMUM_ALLOWED))
    );
}

#[test]
fn key_fd_open_view_captures_guid_path_ancestry_watch_and_granted_mask() {
    let limits = LcsLimits::default();
    let path = ["Machine", "Software"];
    let ancestry = [ROOT, CHILD];
    let fd = fd_view(&path, &ancestry, KEY_READ);

    assert_eq!(validate_key_fd_open_view(&limits, &fd), Ok(()));
}

#[test]
fn key_fd_open_view_fails_closed_on_malformed_snapshot() {
    let limits = LcsLimits::default();
    let path = ["Machine", "Software"];
    let ancestry = [ROOT, CHILD];

    let nil_key = KeyFdOpenView {
        key_guid: NIL_GUID,
        ..fd_view(&path, &ancestry, KEY_READ)
    };
    assert_eq!(
        validate_key_fd_open_view(&limits, &nil_key),
        Err(LcsError::NilKeyGuid)
    );

    let short_ancestry = [ROOT];
    assert_eq!(
        validate_key_fd_open_view(&limits, &fd_view(&path, &short_ancestry, KEY_READ)),
        Err(LcsError::InvalidFdAncestry)
    );

    let wrong_last_guid = [ROOT, ROOT];
    assert_eq!(
        validate_key_fd_open_view(&limits, &fd_view(&path, &wrong_last_guid, KEY_READ)),
        Err(LcsError::InvalidFdAncestry)
    );

    let bad_component = ["Machine", "Bad\\Name"];
    assert_eq!(
        validate_key_fd_open_view(&limits, &fd_view(&bad_component, &ancestry, KEY_READ)),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );
}

#[test]
fn key_fd_access_checks_use_only_cached_granted_mask() {
    assert_eq!(key_fd_granted_access_allows(KEY_READ, KEY_READ), Ok(true));
    assert_eq!(
        key_fd_granted_access_allows(KEY_READ, KEY_SET_VALUE),
        Ok(false)
    );
    assert_eq!(
        key_fd_granted_access_allows(KEY_READ | GENERIC_READ, KEY_READ),
        Err(LcsError::UnknownAccessBits(GENERIC_READ))
    );
}

#[test]
fn fd_delegation_transfers_the_stored_granted_mask() {
    let limits = LcsLimits::default();
    let path = ["Machine", "Software"];
    let ancestry = [ROOT, CHILD];
    let fd = fd_view(&path, &ancestry, KEY_READ | KEY_SET_VALUE);

    assert_eq!(
        plan_key_fd_delegation(&limits, &fd),
        Ok(KeyFdDelegationPlan {
            delegated_granted_access: KEY_READ | KEY_SET_VALUE,
        })
    );
}
