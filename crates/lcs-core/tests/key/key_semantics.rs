use crate::common::{limits};
use lcs_core::{
    Guid, KEY_CREATE_LINK, KEY_CREATE_SUB_KEY, KeyCreateOptions, KeyCreatePlan, KeyCreateRequest,
    KeyParent, KeyRecordView, LcsError, NIL_GUID, REG_OPTION_CREATE_LINK,
    REG_OPTION_VOLATILE, validate_key_create_flags, validate_key_create_request,
    validate_key_record, validate_symlink_create_authority,
};

const PARENT_GUID: Guid = [0x10; 16];
const CHILD_GUID: Guid = [0x11; 16];
const ROOT_GUID: Guid = [0x12; 16];


fn create_request<'a>(flags: u32) -> KeyCreateRequest<'a> {
    KeyCreateRequest {
        parent_guid: PARENT_GUID,
        parent_is_volatile: false,
        parent_granted_access: KEY_CREATE_SUB_KEY,
        child_name: "Software",
        child_guid: CHILD_GUID,
        flags,
        caller_has_tcb_or_admin: false,
    }
}

#[test]
fn key_record_validation_accepts_hive_roots_and_child_records() {
    let limits = limits();
    let root = KeyRecordView {
        guid: ROOT_GUID,
        name: "Machine",
        parent: KeyParent::HiveRoot,
        volatile: false,
        symlink: false,
    };
    let child = KeyRecordView {
        guid: CHILD_GUID,
        name: "Software",
        parent: KeyParent::Parent(ROOT_GUID),
        volatile: true,
        symlink: true,
    };

    assert_eq!(validate_key_record(&limits, &root), Ok(root));
    assert_eq!(validate_key_record(&limits, &child), Ok(child));
}

#[test]
fn key_record_validation_rejects_malformed_identity_and_names() {
    let limits = limits();

    assert_eq!(
        validate_key_record(
            &limits,
            &KeyRecordView {
                guid: NIL_GUID,
                name: "Machine",
                parent: KeyParent::HiveRoot,
                volatile: false,
                symlink: false,
            },
        ),
        Err(LcsError::NilKeyGuid)
    );

    assert_eq!(
        validate_key_record(
            &limits,
            &KeyRecordView {
                guid: CHILD_GUID,
                name: "Bad/Name",
                parent: KeyParent::Parent(ROOT_GUID),
                volatile: false,
                symlink: false,
            },
        ),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );

    assert_eq!(
        validate_key_record(
            &limits,
            &KeyRecordView {
                guid: CHILD_GUID,
                name: "Software",
                parent: KeyParent::Parent(NIL_GUID),
                volatile: false,
                symlink: false,
            },
        ),
        Err(LcsError::NilParentGuid)
    );
}

#[test]
fn key_create_flags_parse_known_bits_and_reject_unknown_bits() {
    assert_eq!(
        validate_key_create_flags(0),
        Ok(KeyCreateOptions {
            volatile: false,
            symlink: false,
        })
    );
    assert_eq!(
        validate_key_create_flags(REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK),
        Ok(KeyCreateOptions {
            volatile: true,
            symlink: true,
        })
    );
    assert_eq!(
        validate_key_create_flags(REG_OPTION_VOLATILE | 0x80),
        Err(LcsError::UnknownCreateFlags {
            flags: REG_OPTION_VOLATILE | 0x80,
            unknown: 0x80,
        })
    );
}

#[test]
fn key_create_request_accepts_ordinary_and_volatile_children() {
    let limits = limits();

    assert_eq!(
        validate_key_create_request(&limits, &create_request(0)),
        Ok(KeyCreatePlan {
            guid: CHILD_GUID,
            name: "Software",
            parent_guid: PARENT_GUID,
            volatile: false,
            symlink: false,
        })
    );

    let mut volatile_child = create_request(REG_OPTION_VOLATILE);
    volatile_child.parent_is_volatile = true;
    assert_eq!(
        validate_key_create_request(&limits, &volatile_child),
        Ok(KeyCreatePlan {
            guid: CHILD_GUID,
            name: "Software",
            parent_guid: PARENT_GUID,
            volatile: true,
            symlink: false,
        })
    );
}

#[test]
fn key_create_request_rejects_invalid_guids_names_and_parent_access() {
    let limits = limits();

    let mut nil_parent = create_request(0);
    nil_parent.parent_guid = NIL_GUID;
    assert_eq!(
        validate_key_create_request(&limits, &nil_parent),
        Err(LcsError::NilParentGuid)
    );

    let mut nil_child = create_request(0);
    nil_child.child_guid = NIL_GUID;
    assert_eq!(
        validate_key_create_request(&limits, &nil_child),
        Err(LcsError::NilKeyGuid)
    );

    let mut bad_name = create_request(0);
    bad_name.child_name = "Bad\\Name";
    assert_eq!(
        validate_key_create_request(&limits, &bad_name),
        Err(LcsError::NameContainsSeparator {
            field: "key_component",
        })
    );

    let mut missing_create_sub_key = create_request(0);
    missing_create_sub_key.parent_granted_access = KEY_CREATE_LINK;
    assert_eq!(
        validate_key_create_request(&limits, &missing_create_sub_key),
        Err(LcsError::MissingKeyCreateSubKey)
    );
}

#[test]
fn key_create_request_enforces_volatile_parent_rule() {
    let limits = limits();
    let mut request = create_request(0);
    request.parent_is_volatile = true;

    assert_eq!(
        validate_key_create_request(&limits, &request),
        Err(LcsError::NonVolatileChildUnderVolatile)
    );
}

#[test]
fn key_create_request_enforces_symlink_creation_authority() {
    let limits = limits();

    let mut missing_link_right = create_request(REG_OPTION_CREATE_LINK);
    missing_link_right.parent_granted_access = KEY_CREATE_SUB_KEY;
    missing_link_right.caller_has_tcb_or_admin = true;
    assert_eq!(
        validate_key_create_request(&limits, &missing_link_right),
        Err(LcsError::MissingKeyCreateLink)
    );

    let mut missing_privilege = create_request(REG_OPTION_CREATE_LINK);
    missing_privilege.parent_granted_access = KEY_CREATE_SUB_KEY | KEY_CREATE_LINK;
    assert_eq!(
        validate_key_create_request(&limits, &missing_privilege),
        Err(LcsError::MissingSymlinkCreationAuthority)
    );

    let mut allowed = create_request(REG_OPTION_CREATE_LINK);
    allowed.parent_granted_access = KEY_CREATE_SUB_KEY | KEY_CREATE_LINK;
    allowed.caller_has_tcb_or_admin = true;
    assert_eq!(
        validate_key_create_request(&limits, &allowed),
        Ok(KeyCreatePlan {
            guid: CHILD_GUID,
            name: "Software",
            parent_guid: PARENT_GUID,
            volatile: false,
            symlink: true,
        })
    );
}

#[test]
fn symlink_authority_helper_distinguishes_right_and_privilege_failures() {
    assert_eq!(
        validate_symlink_create_authority(KEY_CREATE_SUB_KEY, true),
        Err(LcsError::MissingKeyCreateLink)
    );
    assert_eq!(
        validate_symlink_create_authority(KEY_CREATE_LINK, false),
        Err(LcsError::MissingSymlinkCreationAuthority)
    );
    assert_eq!(
        validate_symlink_create_authority(KEY_CREATE_LINK, true),
        Ok(())
    );
}
