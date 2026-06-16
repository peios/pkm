use lcs_core::{
    Guid, HiveRouteErrno, HiveRouteOutcome, HiveScope, HiveStatus, HiveView, LcsError, PathKind,
    route_symlink_target_hive, validate_symlink_target_bytes,
};

const MACHINE_ROOT: Guid = [0x51; 16];
const USERS_ROOT: Guid = [0x52; 16];
const SOURCE_ID: u32 = 7;

fn hives<'a>() -> [HiveView<'a>; 2] {
    [
        HiveView {
            name: "Machine",
            root_guid: MACHINE_ROOT,
            source_id: SOURCE_ID,
            status: HiveStatus::Active,
            scope: HiveScope::Global,
        },
        HiveView {
            name: "Users",
            root_guid: USERS_ROOT,
            source_id: SOURCE_ID,
            status: HiveStatus::Active,
            scope: HiveScope::Global,
        },
    ]
}

#[test]
fn reg_link_payload_is_length_delimited_utf8_path_without_trailing_null() {
    let target = validate_symlink_target_bytes(&Default::default(), b"Machine/Software/App")
        .expect("slash-separated REG_LINK target should validate");

    assert_eq!(target.kind, PathKind::SymlinkTarget);
    assert_eq!(target.raw, "Machine/Software/App");
    assert_eq!(target.first_component, "Machine");
    assert_eq!(target.final_component, "App");
    assert!(target.used_forward_separator);

    assert_eq!(
        validate_symlink_target_bytes(&Default::default(), b"Machine\\Software\0"),
        Err(LcsError::NullByte { field: "path" })
    );
    assert_eq!(
        validate_symlink_target_bytes(&Default::default(), &[0xff]),
        Err(LcsError::InvalidUtf8 { field: "path" })
    );
}

#[test]
fn reg_link_targets_use_absolute_hive_routing() {
    let hives = hives();
    let outcome =
        route_symlink_target_hive(&Default::default(), &hives, b"Machine\\Software\\App", &[])
            .expect("valid absolute target should route");

    let HiveRouteOutcome::Dispatch(route) = outcome else {
        panic!("Machine target should route to the Machine hive");
    };
    assert_eq!(route.name, "Machine");
    assert_eq!(route.root_guid, MACHINE_ROOT);
    assert_eq!(route.source_id, SOURCE_ID);
}

#[test]
fn reg_link_targets_do_not_use_current_user_rewrite_or_relative_resolution() {
    let hives = hives();

    assert_eq!(
        route_symlink_target_hive(&Default::default(), &hives, b"CurrentUser\\Software", &[])
            .expect("literal CurrentUser target should still structurally validate"),
        HiveRouteOutcome::Failure(HiveRouteErrno::Enoent)
    );
    assert_eq!(
        route_symlink_target_hive(&Default::default(), &hives, b"Software\\App", &[])
            .expect("relative-looking target is still routed as an absolute hive path"),
        HiveRouteOutcome::Failure(HiveRouteErrno::Enoent)
    );
}

#[test]
fn reg_link_targets_reuse_registry_path_structure_rules() {
    assert_eq!(
        validate_symlink_target_bytes(&Default::default(), b""),
        Err(LcsError::EmptyPath)
    );
    assert_eq!(
        validate_symlink_target_bytes(&Default::default(), b"Machine\\\\Software"),
        Err(LcsError::EmptyPathComponent)
    );
    assert_eq!(
        validate_symlink_target_bytes(&Default::default(), b"Machine\\Software\\"),
        Err(LcsError::TrailingPathSeparator)
    );
}
