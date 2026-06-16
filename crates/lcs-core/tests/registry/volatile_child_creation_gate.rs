use lcs_core::{
    Guid, KEY_CREATE_SUB_KEY, KeyCreatePlan, KeyCreateRequest, LcsError, LcsLimits,
    REG_OPTION_VOLATILE, RSI_REQUEST_HEADER_LEN, parse_rsi_create_key_request_payload,
    validate_key_create_request, write_rsi_create_key_request_frame,
};

const PARENT_GUID: Guid = [0x21; 16];
const CHILD_GUID: Guid = [0x22; 16];
const CHILD_NAME: &str = "Runtime";
const CHILD_SD: &[u8] = b"self-relative-child-sd";

fn request(flags: u32, parent_is_volatile: bool) -> KeyCreateRequest<'static> {
    KeyCreateRequest {
        parent_guid: PARENT_GUID,
        parent_is_volatile,
        parent_granted_access: KEY_CREATE_SUB_KEY,
        child_name: CHILD_NAME,
        child_guid: CHILD_GUID,
        flags,
        caller_has_tcb_or_admin: false,
    }
}

#[test]
fn nonvolatile_child_under_volatile_parent_fails_before_source_payload() {
    let limits = LcsLimits::default();

    assert_eq!(
        validate_key_create_request(&limits, &request(0, true)),
        Err(LcsError::NonVolatileChildUnderVolatile)
    );
}

#[test]
fn volatile_child_under_volatile_parent_produces_volatile_create_plan() {
    let limits = LcsLimits::default();

    assert_eq!(
        validate_key_create_request(&limits, &request(REG_OPTION_VOLATILE, true)),
        Ok(KeyCreatePlan {
            guid: CHILD_GUID,
            name: CHILD_NAME,
            parent_guid: PARENT_GUID,
            volatile: true,
            symlink: false,
        })
    );
}

#[test]
fn volatile_child_plan_carries_volatile_flag_into_source_create_payload() {
    let limits = LcsLimits::default();
    let plan = validate_key_create_request(&limits, &request(REG_OPTION_VOLATILE, true)).unwrap();
    let mut frame = [0u8; 128];

    let built = write_rsi_create_key_request_frame(
        &mut frame,
        130,
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
    assert!(payload.volatile);
    assert!(!payload.symlink);
}

#[test]
fn volatile_child_under_nonvolatile_parent_is_allowed() {
    let limits = LcsLimits::default();

    assert!(validate_key_create_request(&limits, &request(REG_OPTION_VOLATILE, false)).is_ok());
}
