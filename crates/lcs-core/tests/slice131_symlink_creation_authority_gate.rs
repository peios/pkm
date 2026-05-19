use lcs_core::{
    Guid, KEY_CREATE_LINK, KEY_CREATE_SUB_KEY, KeyCreatePlan, KeyCreateRequest, LcsError,
    LcsLimits, REG_OPTION_CREATE_LINK, RSI_REQUEST_HEADER_LEN,
    parse_rsi_create_key_request_payload, validate_key_create_request,
    write_rsi_create_key_request_frame,
};

const PARENT_GUID: Guid = [0x31; 16];
const CHILD_GUID: Guid = [0x32; 16];
const CHILD_NAME: &str = "Link";
const CHILD_SD: &[u8] = b"self-relative-link-sd";

fn request(parent_granted_access: u32, caller_has_tcb_or_admin: bool) -> KeyCreateRequest<'static> {
    KeyCreateRequest {
        parent_guid: PARENT_GUID,
        parent_is_volatile: false,
        parent_granted_access,
        child_name: CHILD_NAME,
        child_guid: CHILD_GUID,
        flags: REG_OPTION_CREATE_LINK,
        caller_has_tcb_or_admin,
    }
}

#[test]
fn symlink_creation_requires_parent_create_link_right() {
    let limits = LcsLimits::default();

    assert_eq!(
        validate_key_create_request(&limits, &request(KEY_CREATE_SUB_KEY, true)),
        Err(LcsError::MissingKeyCreateLink)
    );
}

#[test]
fn symlink_creation_requires_tcb_or_administrator_authority() {
    let limits = LcsLimits::default();

    assert_eq!(
        validate_key_create_request(
            &limits,
            &request(KEY_CREATE_SUB_KEY | KEY_CREATE_LINK, false),
        ),
        Err(LcsError::MissingSymlinkCreationAuthority)
    );
}

#[test]
fn symlink_creation_with_both_gates_produces_symlink_create_plan() {
    let limits = LcsLimits::default();

    assert_eq!(
        validate_key_create_request(
            &limits,
            &request(KEY_CREATE_SUB_KEY | KEY_CREATE_LINK, true)
        ),
        Ok(KeyCreatePlan {
            guid: CHILD_GUID,
            name: CHILD_NAME,
            parent_guid: PARENT_GUID,
            volatile: false,
            symlink: true,
        })
    );
}

#[test]
fn symlink_create_plan_carries_symlink_flag_into_source_payload() {
    let limits = LcsLimits::default();
    let plan = validate_key_create_request(
        &limits,
        &request(KEY_CREATE_SUB_KEY | KEY_CREATE_LINK, true),
    )
    .unwrap();
    let mut frame = [0u8; 128];

    let built = write_rsi_create_key_request_frame(
        &mut frame,
        131,
        0,
        plan.guid,
        plan.name.as_bytes(),
        plan.parent_guid,
        CHILD_SD,
        plan.volatile,
        plan.symlink,
    )
    .unwrap();
    let payload =
        parse_rsi_create_key_request_payload(&frame[RSI_REQUEST_HEADER_LEN..built.len]).unwrap();

    assert_eq!(payload.guid, CHILD_GUID);
    assert_eq!(payload.name.data, CHILD_NAME.as_bytes());
    assert_eq!(payload.parent_guid, PARENT_GUID);
    assert_eq!(payload.sd.data, CHILD_SD);
    assert!(!payload.volatile);
    assert!(payload.symlink);
}
