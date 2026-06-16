use lcs_core::{
    Guid, LcsError, REG_OPEN_LINK, RegistryKeyOpenResolutionInput, RegistryOpenAccessTarget,
    RegistryValueType, SymlinkDefaultValue, plan_registry_key_open_resolution,
    validate_symlink_default_value,
};

const LINK_GUID: Guid = [0x31; 16];
const TARGET_GUID: Guid = [0x32; 16];
const ORDINARY_GUID: Guid = [0x33; 16];
const NIL_GUID: Guid = [0; 16];

fn open_input(
    final_key_guid: Guid,
    final_component_is_symlink: bool,
    symlink_target_guid: Option<Guid>,
    flags: u32,
) -> RegistryKeyOpenResolutionInput {
    RegistryKeyOpenResolutionInput {
        final_key_guid,
        final_component_is_symlink,
        symlink_target_guid,
        flags,
    }
}

#[test]
fn ordinary_symlink_open_requires_target_and_publishes_target_fd() {
    validate_symlink_default_value(
        &Default::default(),
        Some(SymlinkDefaultValue {
            value_type: RegistryValueType::Link,
            data: b"Machine\\Resolved",
        }),
    )
    .expect("effective REG_LINK target should validate before path resolution");

    let plan = plan_registry_key_open_resolution(open_input(LINK_GUID, true, Some(TARGET_GUID), 0))
        .expect("ordinary symlink open should follow target");

    assert_eq!(plan.access_target, RegistryOpenAccessTarget::SymlinkTarget);
    assert_eq!(plan.access_check_key_guid, TARGET_GUID);
    assert_eq!(plan.published_fd_key_guid, TARGET_GUID);
    assert!(plan.follows_symlink);
}

#[test]
fn open_link_flag_publishes_link_key_without_resolving_target() {
    let plan = plan_registry_key_open_resolution(open_input(LINK_GUID, true, None, REG_OPEN_LINK))
        .expect("REG_OPEN_LINK should open the symlink key itself");

    assert_eq!(plan.access_target, RegistryOpenAccessTarget::SymlinkKey);
    assert_eq!(plan.access_check_key_guid, LINK_GUID);
    assert_eq!(plan.published_fd_key_guid, LINK_GUID);
    assert!(!plan.follows_symlink);
}

#[test]
fn non_symlink_open_publishes_final_key_even_with_open_link_flag() {
    let plan =
        plan_registry_key_open_resolution(open_input(ORDINARY_GUID, false, None, REG_OPEN_LINK))
            .expect("REG_OPEN_LINK is only meaningful for symlink keys");

    assert_eq!(plan.access_target, RegistryOpenAccessTarget::FinalKey);
    assert_eq!(plan.access_check_key_guid, ORDINARY_GUID);
    assert_eq!(plan.published_fd_key_guid, ORDINARY_GUID);
    assert!(!plan.follows_symlink);
}

#[test]
fn ordinary_symlink_open_fails_closed_without_resolved_target() {
    assert_eq!(
        plan_registry_key_open_resolution(open_input(LINK_GUID, true, None, 0)),
        Err(LcsError::SymlinkDefaultValueMissing)
    );
    assert_eq!(
        plan_registry_key_open_resolution(open_input(LINK_GUID, true, Some(NIL_GUID), 0)),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        plan_registry_key_open_resolution(open_input(NIL_GUID, true, Some(TARGET_GUID), 0)),
        Err(LcsError::NilKeyGuid)
    );
    assert_eq!(
        plan_registry_key_open_resolution(open_input(LINK_GUID, true, Some(TARGET_GUID), 0x80)),
        Err(LcsError::UnknownOpenFlags {
            flags: 0x80,
            unknown: 0x80,
        })
    );
}
